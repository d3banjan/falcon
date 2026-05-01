# Falcon / pickle-stubs-secure

[![CI](https://github.com/d3banjan/falcon/actions/workflows/ci.yml/badge.svg)](https://github.com/d3banjan/falcon/actions/workflows/ci.yml)
[![Pages](https://github.com/d3banjan/falcon/actions/workflows/pages.yml/badge.svg)](https://github.com/d3banjan/falcon/actions/workflows/pages.yml)

Falcon turns pickle-backed deserialization risk into a type-checking gate.

The project ships Python stubs that mark dangerous deserialization APIs as `Unsafe[Any]`. Under strict `mypy` or `pyright`, application code cannot silently treat those values as trusted data. Intentional trust must be written as `cast(...)` and can be enumerated by `pickle-secure audit`.

Microsite: <https://d3banjan.github.io/falcon/>

## Why

Many CVEs are not fixed everywhere at once. Applications pin old versions, vendors disagree about threat models, and "trusted input only" often becomes a deployment assumption rather than an enforceable boundary.

Falcon does not patch upstream packages. It blocks unaudited vulnerable use in downstream application code before deployment.

## Minimal Example

```python
from typing import Any, cast
import pickle
import numpy as np

def unsafe_session(raw: bytes) -> dict[str, Any]:
    return pickle.loads(raw)  # type error: Unsafe[Any]

def unsafe_model(path: str) -> dict[str, Any]:
    return np.load(path, allow_pickle=True)  # type error: Unsafe[Any]

def reviewed(raw: bytes) -> dict[str, Any]:
    return cast(dict[str, Any], pickle.loads(raw))  # trust: migration reviewed inbound artifact
```

The first two flows fail under the strict profile. The reviewed flow type-checks, but `pickle-secure audit` reports the trust boundary.

## Current Scope

Core stdlib surfaces:

- `pickle.load`, `pickle.loads`, `pickle.Unpickler.load`
- `_pickle.load`, `_pickle.loads`, `_pickle.Unpickler.load`
- `shelve` read paths: `__getitem__`, `get`, `values`, `items`
- adjacent deserialization sinks: `cloudpickle.load`, `cloudpickle.loads`, `jsonpickle.decode`, `jsonpickle.loads`, `dill.load`, `dill.loads`, `joblib.load`, `marshal.load`, `marshal.loads`, `pandas.read_pickle`, `pandas.io.pickle.read_pickle`, `yaml.load`, `yaml.unsafe_load`, `yaml.full_load`

CVE-backed downstream pilot surfaces:

- `numpy.load(..., allow_pickle=True)`
- LangChain / langchain-community FAISS deserialization
- Kedro `ShelveStore` reads
- LlamaIndex `JsonPickleSerializer`
- pyfory pickle fallback APIs
- python-socketio queue manager handlers
- Pipecat LiveKit frame deserializer
- torch_musa compare utilities
- PyTorch `torch.load`
- cloudpickle/jsonpickle CVE sink-family stubs

See [cve_db/reports/downstream-stubs-2026-04-30.md](cve_db/reports/downstream-stubs-2026-04-30.md) for the current CVE verdicts.
See [cve_db/reports/osv-deserialization-candidates-2026-05-01.md](cve_db/reports/osv-deserialization-candidates-2026-05-01.md) for the expanded OSV candidate run.

## Install

```bash
pip install pickle-stubs-secure
```

For local development from this repo:

```bash
uv sync --all-groups
uv run pytest tests/ -q
```

## Strict Profile

```bash
pickle-secure init --profile=strict --write-precommit
mypy --strict .
pyright .
pickle-secure audit .
```

`pickle-secure init` configures checker stub paths and audit policy. The strict profile also tightens common escape routes such as unchecked `Any`, blank ignores, and dynamic access patterns.

## Repository Layout

- `src/pickle_stubs_secure/` - runtime package and CLI.
- `stubs/` - canonical checker overlay used by `mypy_path` / `stubPath`.
- `pickle-stubs/` - packaged stub copy shipped in the wheel.
- `cve_db/` - machine-readable CVE evidence and coverage reports.
- `docs/` - GitHub Pages microsite source.
- `lean/` - separate formal model work.
- `tests/` - runtime, checker, CLI, CVE, and feature tests.

The duplicate-looking `stubs/` and `pickle-stubs/` trees are intentional for now: one is the canonical local overlay, the other is the packaged distribution copy.

## Formal Method Boundary

Falcon uses `Unsafe[T]` as a type-level taint marker. The Lean model explains the methodology: unsafe sources should not reach trusted typed sinks without an explicit escape. In real projects, the executable proof artifact is the CI type-checker run.

This is not a proof that Python, mypy, pyright, or every dependency is sound. It is a practical gate for vulnerability branches that can be expressed as typed source-to-sink flows.

## What Is Out of Scope

- Proving load-time RCE cannot occur. That needs future `TrustedBytes` / `TrustedPath` types.
- Authorization, SSRF, path traversal, crypto, race conditions, and business logic CVEs.
- Full type modeling of every downstream package.
- Replacing Bandit, Semgrep, Ruff, SAST, or dependency scanning.

## Links

- Docs: <https://d3banjan.github.io/falcon/>
- CVE workflow: [docs/cve-database.md](docs/cve-database.md)
- Launch quiz: [docs/launch-quiz.md](docs/launch-quiz.md)
- Architecture: [docs/architecture.md](docs/architecture.md)

## License

MIT

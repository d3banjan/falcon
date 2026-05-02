# Falcon

[![CI](https://github.com/d3banjan/falcon/actions/workflows/ci.yml/badge.svg)](https://github.com/d3banjan/falcon/actions/workflows/ci.yml)
[![Pages](https://github.com/d3banjan/falcon/actions/workflows/pages.yml/badge.svg)](https://github.com/d3banjan/falcon/actions/workflows/pages.yml)

Falcon turns pickle-backed deserialization risk into a type-checking gate.

The project ships Python stubs that mark dangerous deserialization APIs as `Unsafe[Any]`. Selected real loaders also require explicit provenance wrappers such as `TrustedBytes` or `TrustedPath` before the call. Under strict `mypy` or `pyright`, application code cannot silently treat deserialized values as trusted data, and selected call-time gates reject raw bytes, paths, and file handles before deserialization. Intentional trust must be written as `cast(...)` and can be enumerated by `falcon-secure audit`.

Microsite: <https://d3banjan.github.io/falcon/>

## Why

Many CVEs are not fixed everywhere at once. Applications pin old versions, vendors disagree about threat models, and "trusted input only" often becomes a deployment assumption rather than an enforceable boundary.

Falcon does not patch upstream packages. It blocks unaudited vulnerable use in downstream application code before deployment.

## Minimal Example

```python
from typing import Any, cast
import pickle
import numpy as np
from falcon_secure.trust import trusted_bytes

def unsafe_session(raw: bytes) -> dict[str, Any]:
    return pickle.loads(raw)  # type error: raw bytes are not TrustedBytes

def unsafe_model(path: str) -> dict[str, Any]:
    return np.load(path, allow_pickle=True)  # type error: Unsafe[Any]

def reviewed(raw: bytes) -> dict[str, Any]:
    payload = trusted_bytes(raw, reason="migration reviewed inbound artifact")
    return cast(dict[str, Any], pickle.loads(payload))  # trust: migration reviewed inbound artifact
```

The first two flows fail under the strict profile. The reviewed flow type-checks, but `falcon-secure audit` reports the cast boundary and the trusted-input promotion.

## Current Scope

Core stdlib surfaces:

- `pickle.load`, `pickle.Unpickler.load`
- `pickle.loads` requires `TrustedBytes` and still returns `Unsafe[Any]`
- `_pickle.load`, `_pickle.loads`, `_pickle.Unpickler.load`
- `shelve` read paths: `__getitem__`, `get`, `values`, `items`
- adjacent deserialization sinks: `cloudpickle.load` requires `TrustedBinaryIO`, `cloudpickle.loads` requires `TrustedBytes`, `jsonpickle.decode`, `jsonpickle.loads`, `dill.load` requires `TrustedBinaryIO`, `dill.loads` requires `TrustedBytes`, `joblib.load`, `marshal.load`, `marshal.loads`, `pandas.read_pickle`, `pandas.io.pickle.read_pickle`, `yaml.load`, `yaml.unsafe_load`, `yaml.full_load`

CVE-backed downstream pilot surfaces:

- `numpy.load(..., allow_pickle=True)`
- LangChain / langchain-community FAISS deserialization
- Kedro `ShelveStore` `__getitem__`, `get`, and `load`
- LlamaIndex `JsonPickleSerializer.deserialize`
- pyfory pickle fallback APIs
- python-socketio queue manager emit/callback handlers
- Pipecat LiveKit frame deserializer
- torch_musa compare utilities
- PyTorch `torch.load` requires `TrustedPath` and still returns `Unsafe[Any]`
- vLLM PyTorch weight iterators
- InvokeAI model-loading helpers
- Horovod cloudpickle codec
- smolagents remote executor `deserialize` and `loads`
- cloudpickle/jsonpickle CVE sink-family stubs
- `joblib.load`, pandas `read_pickle`, and pandas `io.pickle.read_pickle`
  require `TrustedPath` and still return `Unsafe[Any]`

See [cve_db/reports/downstream-stubs-2026-04-30.md](cve_db/reports/downstream-stubs-2026-04-30.md) for the current CVE verdicts.
See [cve_db/reports/osv-deserialization-candidates-2026-05-01.md](cve_db/reports/osv-deserialization-candidates-2026-05-01.md) for the expanded OSV candidate run.

## Install

```bash
# Install Falcon.
pip install falcon-secure
```

The installed distribution is `falcon-secure`; the runtime import path is
`falcon_secure`, the CLI is `falcon-secure`, and local policy lives under
`[tool.falcon_secure]`.

For local development from this repo:

```bash
uv sync --all-groups
uv run pytest tests/ -q
```

## Strict Profile

```bash
falcon-secure init --profile=strict --write-precommit
mypy --strict .
pyright .
falcon-secure audit .
```

`falcon-secure init` configures checker stub paths and audit policy. The strict profile also tightens common escape routes such as unchecked `Any`, blank ignores, and dynamic access patterns.

## Repository Layout

- `src/falcon_secure/` - runtime package and CLI.
- `stubs/` - canonical checker overlay used by `mypy_path` / `stubPath`.
- `falcon-stubs/` - packaged stub distribution tree; treat this as a packaging implementation detail.
- `cve_db/` - machine-readable CVE evidence and coverage reports.
- `docs/` - GitHub Pages microsite source.
- `lean/` - separate formal model work.
- `tests/` - runtime, checker, CLI, CVE, and feature tests.

The duplicate-looking local and packaged stub trees are intentional for now: one is the canonical local overlay, the other is the packaged distribution copy.

## Formal Method Boundary

Falcon uses `Unsafe[T]` as a type-level taint marker. The Lean model explains the methodology: unsafe sources should not reach trusted typed sinks without an explicit escape. In real projects, the executable proof artifact is the CI type-checker run.

This is not a proof that Python, mypy, pyright, or every dependency is sound. It is a practical gate for vulnerability branches that can be expressed as typed source-to-sink flows.

## What Is Out of Scope

- Proving load-time RCE cannot occur across arbitrary APIs. The Lean model and
  selected real API stubs now cover the `TrustedBytes` / `TrustedBinaryIO` /
  `TrustedPath` boundary for `pickle.loads`, `cloudpickle.load(s)`,
  `dill.load(s)`, `joblib.load`, pandas pickle helpers, and `torch.load`, but
  broad third-party API adoption remains future work.
- Authorization, SSRF, path traversal, crypto, race conditions, and business logic CVEs.
- Full type modeling of every downstream package.
- Replacing Bandit, Semgrep, Ruff, SAST, or dependency scanning.

## Links

- Docs: <https://d3banjan.github.io/falcon/>
- CVE workflow: [docs/cve-database.md](docs/cve-database.md)
- Launch quiz: [docs/launch-quiz.md](docs/launch-quiz.md)
- Architecture: [docs/architecture.md](docs/architecture.md)
- Current handoff: [docs/session-handoff-2026-05-02.md](docs/session-handoff-2026-05-02.md)

## License

MIT

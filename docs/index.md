---
layout: page
title: Falcon
---

{% include research_status.html %}

Software security is usually a systems problem, not a single-line problem.

A vulnerability becomes expensive when unsafe behavior is allowed to travel through a codebase unnoticed: a library accepts bytes, a helper deserializes them, application code treats the result as trusted, and CI sees ordinary Python. The payoff of Falcon is to move that risk earlier. Instead of waiting for every upstream package, deployment, and reviewer to line up perfectly, Falcon lets application teams block unsafe use at the type-checking step.

## The method

Falcon uses custom type annotations as a lightweight taint system.

Dangerous APIs are annotated to return `Unsafe[T]`. If application code tries to use that value as an ordinary trusted type, `mypy`, `pyright`, or `ty` rejects the program. If a developer really intends to trust the value, they must write an explicit `cast(...)` and attach a `# trust:` reason. That cast becomes the reviewable boundary.

In security terms, the vulnerable line is no longer invisible. It is tainted in the type system.

## Where formal methods enter

The Lean model explains why this methodology is coherent:

- unsafe deserialization APIs are sources;
- typed application values are sinks;
- `Unsafe[T]` marks values that cannot silently cross the boundary;
- `cast(...)` is the explicit proof obligation or trust assertion.

Lean backs the shape of the argument: in a sound fragment, unsafe values do not reach trusted sinks without an explicit escape. The operational proof artifact in a real project is the CI run: the typechecker either accepts the audited program or blocks the deployment.

Falcon does not claim that CPython, mypy, pyright, or every dependency is formally verified. It claims something narrower and useful: for vulnerability branches that can be expressed as typed source-to-sink flows, annotated stubs turn the checker into a deploy-time gate.

## Why this matters for CVEs

Many CVEs are not fixed everywhere at once. Projects pin old versions, vendors disagree about threat models, and some advisories are treated as "trusted input only." Falcon helps downstream application teams anyway: annotated stubs make unsafe deserialization APIs return `Unsafe[Any]`, and strict type-checking blocks unaudited use before deployment.

Current evidence-set coverage: Falcon catches or partially catches 24 / 26 (92%) reviewed Python ecosystem pickle-backed CVEs at the source or sink-family level. The stricter implemented stub number is 16 / 26 (62%). See [Coverage Analysis](coverage-analysis.md) for the per-CVE matrix and CWE boundary.

## Minimal working example

```python
from typing import Any, cast
import pickle
import shelve
import numpy as np

def load_session(raw: bytes) -> dict[str, Any]:
    return pickle.loads(raw)

def load_cache(path: str) -> dict[str, Any]:
    db = shelve.open(path)
    return db["session"]

def load_model(path: str) -> dict[str, Any]:
    return np.load(path, allow_pickle=True)

def reviewed_load(raw: bytes) -> dict[str, Any]:
    return cast(dict[str, Any], pickle.loads(raw))  # trust: migration reviewed inbound artifact
```

`mypy`, `pyright`, and eventually `ty` all see the same core shape: an `Unsafe[Any]` value is being returned as trusted application data. The exact diagnostic wording differs, but CI fails until the code is changed or explicitly reviewed with `cast(...)  # trust:`.

## What Falcon does

- Annotates dangerous APIs with `Unsafe[T]`.
- Lets existing type checkers enforce the gate.
- Enumerates trust escapes with `pickle-secure audit`.
- Maps CVEs and CWEs to concrete stubs and fixtures.

## What Falcon does not claim

Falcon does not patch upstream CVEs. It prevents unaudited vulnerable use from entering your application code.

---
layout: page
title: Falcon
---

{% include research_status.html %}

Falcon is a type-checking enforcement layer for selected Python deserialization flows.

## Current claim

Falcon currently claims: if a codepath is in-scope, dangerous deserialization data cannot pass into trusted typed application state without a reviewable trust boundary (`cast(... )  # trust: ...`). For selected real loader APIs, strict checking also blocks untrusted inputs from reaching the call before load-time execution.

This is a deploy-time CI gate for currently modeled API shapes, not a global runtime safety mechanism.

## Current enforced gates

Falcon enforces two gate classes today:

- **Returned-value quarantine (broad):** dangerous sources return `Unsafe[Any]`. Any downstream trusted use requires an explicit trust boundary.
- **Call-time trusted-input gates (selected real APIs):** selected loader calls now require provenance-gated inputs before execution:
  - `pickle.loads` requires `TrustedBytes`
  - `cloudpickle.loads` and `dill.loads` require `TrustedBytes`
  - `cloudpickle.load` and `dill.load` require `TrustedBinaryIO`
  - `joblib.load`, `pandas.read_pickle`, `pandas.io.pickle.read_pickle`, and `torch.load` require `TrustedPath`
  - selected FAISS, Pipecat, and torch_musa wrapper APIs require `TrustedBytes` or `TrustedPath`

Falcon also models selected conditional unsafe APIs such as `numpy.load(..., allow_pickle=True)` as unsafe-return sources.

Other sinks may only be covered as returned-value quarantine until their real API wrappers adopt preconditions.

## Current coverage numbers

The triaged evidence set remains 26 rows:

- Coverage at source-or-sink-family classification: **24 / 26 (92%)**
- Rows with sink-family or consumer-facing API stubs: **16 / 26 (62%)**
- Broad OSV PyPI triage pass (last run): **221** candidates, with **31** catchable, **37** partial, **49** needing source confirmation, rest excluded from denominator after triage

## Minimal working example

```python
from typing import Any, cast
import pickle
from falcon_secure.trust import trusted_bytes

def blocked(raw: bytes) -> dict[str, Any]:
    return pickle.loads(raw)  # type error: raw bytes are not TrustedBytes

def reviewed(raw: bytes) -> dict[str, Any]:
    safe = trusted_bytes(raw, reason="artifact reviewed")
    return cast(dict[str, Any], pickle.loads(safe))
```

## What is claimed

- strict deploy-time enforcement for the current in-scope sinks
- returned-value quarantine in core and adjacent pickle-family sinks
- selected call-time trusted-input boundaries for specific loader APIs
- conditional unsafe-return checks for selected APIs such as NumPy pickle-backed loading
- explicit trust boundaries captured by `falcon-secure audit`

## What is not claimed

- broad load-time RCE prevention across all APIs
- prevention for analyzers/policy advisories and non-deserialization attack classes
- replacing SAST, dependency scanners, or runtime defenses
- patching upstream packages directly

See:
- [Coverage analysis](coverage-analysis.md)
- [Formal method](formal-method.md)
- [Evidence appendix](cve-triage.md)

---
layout: page
title: CVEs and CWEs
---

# CVEs and CWEs

The CVE database asks one concrete question:

> Can a type stub make vulnerable application use fail in CI?

For each CVE, Falcon records:

- affected package and API;
- linked CWE;
- underlying pickle primitive;
- catchability category;
- required stub;
- checker status;
- verdict: `caught`, `partial`, `miss`, or `out-of-scope`.

## CWE-502 split

CWE-502 has two different claims:

- returned-value quarantine: `pickle.loads` returns `Unsafe[Any]`;
- load-time RCE prevention: untrusted bytes cannot be passed to deserialization at all.

Falcon currently ships the first claim. The second requires future `TrustedBytes` / `TrustedPath` types.

## Current downstream targets

- NumPy `load(..., allow_pickle=True)`
- LangChain FAISS deserializers
- Kedro `ShelveStore`
- LlamaIndex `JsonPickleSerializer`
- pyfory pickle fallback surfaces
- python-socketio queue deserialization internals
- Pipecat LiveKit frame serializer
- torch_musa compare utilities
- PyTorch `torch.load`

See `cve_db/reports/downstream-stubs-2026-04-30.md` for current verdicts.


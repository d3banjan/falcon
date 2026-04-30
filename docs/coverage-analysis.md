---
layout: page
title: Coverage Analysis
---

# Coverage Analysis

{% include research_status.html %}

Last checked: 2026-05-01.

This page measures Falcon against a current evidence set of Python ecosystem CVEs where the relevant exploit path involves `pickle`, `_pickle`, `shelve`, `cloudpickle`, `jsonpickle`, pickle fallback behavior, or package APIs that wrap those sinks.

This is not a count of all CPython CVEs. CPython memory safety, audit-hook, subprocess, import, TLS, path traversal, authorization, and debugger CVEs are outside Falcon unless the vulnerable branch is a typed deserialization source-to-sink flow.

## Headline

| Metric | Count |
|---|---:|
| Evidence-set CVEs reviewed | 26 |
| Currently type-catchable by Falcon's method | 18 / 26 (69%) |
| Implemented as consumer-facing target stubs | 10 / 26 (38%) |
| Missing because sink family is not stubbed yet | 6 / 26 (23%) |
| Out of scope for this method | 2 / 26 (8%) |

The 18 / 26 number includes direct source catches: if the vulnerable project source is type-checked with Falcon's stdlib stubs, calls such as `pickle.loads(...)` become `Unsafe[Any]` and cannot silently flow into trusted typed values. The stricter 10 / 26 number counts only CVEs with current consumer-facing library stubs or conditional API stubs.

## CWE Coverage

| CWE | Falcon verdict | Why |
|---|---|---|
| CWE-502: Deserialization of Untrusted Data | Caught partially | Falcon catches returned-value trust flow from pickle-backed APIs. It does not yet prove that untrusted bytes cannot reach deserialization before code execution. |
| CWE-94: Improper Control of Generation of Code | Partial when mediated by pickle | If the CWE-94 exploit branch is a pickle load path, Falcon can flag the typed deserialization flow. General code-injection bugs are out of scope. |
| CWE-20: Improper Input Validation | Partial when the bad input reaches a stubbed deserializer | Falcon does not prove general validation. It only catches the branch where validation failure becomes unsafe deserialization. |
| CWE-121 / CWE-125: Memory safety | Out of scope | These are CPython/runtime memory-access issues, not Python type-level deserialization flows. |

## Catchable CVE Categories

| Category | Current status | Examples |
|---|---|---|
| Direct stdlib pickle source | Caught in typed source | `pickle.load`, `pickle.loads`, `_pickle`, `shelve` reads. |
| Conditional unsafe API | Implemented for NumPy | `numpy.load(..., allow_pickle=True)`. |
| Public wrapper around pickle | Implemented for selected packages | LangChain FAISS, Kedro `ShelveStore`, LlamaIndex `JsonPickleSerializer`, pyfory, Pipecat, torch_musa, PyTorch. |
| Internal service deserialization | Partial | SocketIO queues, LeRobot gRPC, SGLang ZMQ, Tendenci reports. Falcon can catch source code or return flow, but not deployment trust. |
| Alternate pickle-family libraries | Missing | `cloudpickle` and `jsonpickle` CVEs need new stubs. |
| Analyzer misclassification | Out of scope | Fickling CVEs are about a security analyzer's verdict, not an application value flowing from deserialization. |

## Per-CVE Verdicts

| CVE | Project | Sink family | Falcon verdict |
|---|---|---|---|
| CVE-2019-6446 | NumPy | `numpy.load(..., allow_pickle=True)` | Implemented target stub. |
| CVE-2024-5998 | LangChain | FAISS pickle-backed deserialization | Implemented target stub. |
| CVE-2024-9701 | Kedro | `shelve` wrapper | Implemented target stub. |
| CVE-2025-3108 | LlamaIndex | `pickle.loads` fallback | Implemented target stub. |
| CVE-2025-32434 | PyTorch | `torch.load` | Implemented target stub. |
| CVE-2025-50472 | ModelScope / ms-swift | `pickle.load` | Source catch; public API still needs confirmation. |
| CVE-2025-61622 | pyfory / pyfury | pickle fallback | Implemented target stub. |
| CVE-2025-61765 | python-socketio | queue pickle deserialization | Partial target stub; deployment trust remains out of type scope. |
| CVE-2025-62373 | Pipecat | `pickle.loads` frame deserializer | Implemented target stub. |
| CVE-2025-65213 | torch_musa | `pickle.load` utility path | Implemented target stub. |
| CVE-2025-14931 | smolagents | pickle-backed parsing | Partial placeholder stub; exact API still needs source confirmation. |
| CVE-2025-57622 | Step-Video-T2V | `pickle.loads` endpoint | Source catch only; no stable consumer API identified. |
| CVE-2026-26215 | manga-image-translator | `pickle.loads` endpoint | Source catch only; auth/nonce behavior is out of scope. |
| CVE-2026-25874 | LeRobot | `pickle.loads` over gRPC | Source catch only; channel trust/TLS is out of scope. |
| CVE-2026-23946 | Tendenci | `pickle.loads` report path | Source catch only; authenticated workflow is out of scope. |
| CVE-2025-64512 | pdfminer.six | `pickle.loads` CMap data | Source catch; consumer PDF API would need a target stub or `TrustedPath`. |
| CVE-2026-3059 | SGLang | `pickle.loads` over ZMQ | Source catch only; broker authentication is out of scope. |
| CVE-2025-56005 | PLY | `pickle.load` via `picklefile` | Source catch; disputed CVE and public API policy need confirmation. |
| CVE-2025-62703 | Fugue | `cloudpickle.loads` | Miss: add `cloudpickle` stubs. |
| CVE-2025-6279 | Upsonic | `cloudpickle.loads` | Miss: add `cloudpickle` stubs. |
| CVE-2024-10190 | Horovod | `cloudpickle.loads` wrapper | Miss: add `cloudpickle` and Horovod wrapper stubs. |
| CVE-2024-9053 | vLLM | `cloudpickle.loads` | Miss: add `cloudpickle` stubs. |
| CVE-2024-0960 | ai-flow | `cloudpickle.loads` | Miss: add `cloudpickle` stubs. |
| CVE-2020-22083 | jsonpickle | `jsonpickle.decode` | Miss: add `jsonpickle` stubs; disputed/intended-behavior note required. |
| CVE-2026-22606 | Fickling | analyzer classification | Out of scope. |
| CVE-2026-22607 | Fickling | analyzer classification | Out of scope. |

## What Would Increase Coverage Next

The next high-leverage scope is not packaging. It is stub coverage for alternate pickle-family libraries:

- `cloudpickle.loads`, `cloudpickle.load`;
- `jsonpickle.decode`;
- likely `dill.load`, `dill.loads`, and `joblib.load` as adjacent deserialization surfaces;
- package wrappers around those sinks for Horovod, vLLM, Fugue, Upsonic, and ai-flow.

That would move the currently missing `cloudpickle` / `jsonpickle` records into the type-catchable bucket. It would still not prove load-time RCE prevention; that requires the future `TrustedBytes` / `TrustedPath` proof family.

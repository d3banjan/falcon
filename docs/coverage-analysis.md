---
layout: page
title: Current Coverage
---

{% include research_status.html %}

Last checked: 2026-05-02.

This page is the current coverage status for Falcon against the triaged deserialization evidence set in the Python ecosystem.

Primary scope is the triaged set of 26 CVE rows where the exploit path touches `pickle`, `_pickle`, `shelve`, `cloudpickle`, `jsonpickle`, `dill`, `joblib`, `marshal`, unsafe YAML loading, pickle fallback behavior, or wrappers around those sinks.

A broader OSV PyPI keyword scan (secondary context) produced 221 candidates on 2026-05-01 and remains out of scope for current numerator claims until completed triage.

This is not a full count of all CPython CVEs; memory safety, audit-hook, subprocess, import, TLS, path traversal, authorization, and debugger advisories are excluded unless the vulnerable branch is a typed deserialization source-to-sink flow.

## Headline (Triaged Evidence Set)

| Metric | Count |
|---|---:|
| Triaged evidence-set CVEs reviewed | 26 |
| Covered at source-or-sink-family classification level | 24 / 26 (92%) |
| Rows with sink-family or consumer-facing wrapper stubs | 16 / 26 (62%) |
| Real APIs with trusted-input call preconditions | 9 |
| Missing because sink family is not stubbed yet | 0 / 26 (0%) |
| Out of scope for this method | 2 / 26 (8%) |
| Additional OSV-promoted adjacent sink rows | 11 |

## Claim Tiers

### Call-time gate
Strongest control: execution is blocked unless a trusted input is required before call.

- **Current count:** 9 real APIs with call-time guards.
- Examples: `pickle.loads`, `cloudpickle.load(s)`, `dill.load(s)`, `joblib.load`, pandas `read_pickle`, pandas `io.pickle.read_pickle`, and `torch.load`.

### Conditional unsafe return
Direct call expressions whose unsafe mode can be represented in type stubs.

- Example: `numpy.load(..., allow_pickle=True)`.
- These checks quarantine the returned value; they are not counted as trusted-input preconditions.

### Returned-value quarantine
Source-or-sink-family typed blocks where unsafe deserialization outputs are treated as `Unsafe[Any]` and must be handled explicitly before entering trusted channels.

- **Current count:** 16 / 26 (62%).
- This includes many wrappers and sink-family stubs where Falcon catches the risky return value but does not yet force a trusted-input precondition on every real API entry point.

### Source catch
Direct source-level flow catches from validated fixtures or sink-family typing before a stable target API is fixed.

- **Current count:** included in the 24 / 26 source-or-sink-family figure.
- Coverage here confirms the risky flow shape, not universal API-level load-time prevention.

### Out of scope

- **Current count:** 2 / 26 (8%).
- Includes analyzer-policy advisories and CPython/runtime categories that are outside Falcon’s current model.

## OSV Candidate Context (Secondary)

This candidate set is explicitly secondary context and a triage pipeline input, not a hard denominator.

| OSV bucket | Count | Share |
|---|---:|---:|
| OSV PyPI keyword candidates awaiting triage | 221 | 100% |
| First-pass catchable candidates | 31 | 14% |
| First-pass partial candidates | 37 | 17% |
| First-pass non-denominator candidates | 104 | 47% |
| First-pass needs source confirmation | 49 | 22% |

## CWE Coverage

| CWE | Falcon verdict | Why |
|---|---|---|
| CWE-502: Deserialization of Untrusted Data | Caught partially | Falcon catches returned-value trust flow from pickle-backed APIs and now blocks raw inputs for selected real loaders. It does not yet prove that untrusted bytes cannot reach every deserialization API before code execution. |
| CWE-94: Improper Control of Generation of Code | Partial when mediated by pickle | If the CWE-94 exploit branch is a pickle load path, Falcon can flag the typed deserialization flow. General code-injection bugs are out of scope. |
| CWE-20: Improper Input Validation | Partial when the bad input reaches a stubbed deserializer | Falcon does not prove general validation. It only catches the branch where validation failure becomes unsafe deserialization. |
| CWE-121 / CWE-125: Memory safety | Out of scope | These are CPython/runtime memory-access issues, not Python type-level deserialization flows. |

## Catchable CVE Categories

| Category | Current status | Examples |
|---|---|---|
| Direct stdlib pickle source | Partly caught in typed source; limited call-time gates | `pickle.loads` now requires `TrustedBytes`; `pickle.load`, `_pickle`, and `shelve` reads provide returned-value quarantine. |
| Conditional unsafe API | Implemented for NumPy | `numpy.load(..., allow_pickle=True)`. |
| Public wrapper around pickle | Implemented for selected packages | LangChain FAISS, Kedro `ShelveStore`, LlamaIndex `JsonPickleSerializer`, pyfory, Pipecat, torch_musa, PyTorch, vLLM, InvokeAI, Horovod. |
| Internal service deserialization | Partial | SocketIO queues, LeRobot gRPC, SGLang ZMQ, Tendenci reports. Falcon can catch source code or return flow, but not deployment trust. |
| Alternate pickle-family libraries | Implemented at sink-family level with selected call gates | `cloudpickle.loads` requires `TrustedBytes`, `cloudpickle.load` requires `TrustedBinaryIO`, and `jsonpickle.decode` returns `Unsafe[Any]`. |
| Adjacent Python serialization sinks | Implemented at sink-family or selected wrapper level | `joblib.load` and pandas `read_pickle` require `TrustedPath`; `dill.loads` requires `TrustedBytes`; `dill.load` requires `TrustedBinaryIO`; `marshal.load(s)`, skops `Card.get_model`, Embedchain `OpenAPILoader.load_data`, and unsafe YAML loaders return `Unsafe[Any]`. Most remaining wrappers still need trusted-input adoption before load-time prevention claims. |
| Analyzer misclassification | Out of scope | Fickling CVEs are about a security analyzer's verdict, not an application value flowing from deserialization. |

## Per-CVE Verdicts

| CVE | Project | Sink family | Falcon verdict |
|---|---|---|---|
| CVE-2019-6446 | NumPy | `numpy.load(..., allow_pickle=True)` | Implemented target stub. |
| CVE-2024-5998 | LangChain | FAISS pickle-backed deserialization | Implemented target stub. |
| CVE-2024-9701 | Kedro | `shelve` wrapper | Implemented target stub. |
| CVE-2025-3108 | LlamaIndex | `pickle.loads` fallback | Implemented target stub. |
| CVE-2025-32434 | PyTorch | `torch.load` | Implemented target stub; `torch.load` now requires `TrustedPath` and still returns `Unsafe[Any]`. |
| CVE-2025-50472 | ModelScope / ms-swift | `pickle.load` | Validated source-shaped fixture; public API still needs confirmation. |
| CVE-2025-61622 | pyfory / pyfury | pickle fallback | Implemented target stub. |
| CVE-2025-61765 | python-socketio | queue pickle deserialization | Partial target stub; deployment trust remains out of type scope. |
| CVE-2025-62373 | Pipecat | `pickle.loads` frame deserializer | Implemented target stub. |
| CVE-2025-65213 | torch_musa | `pickle.load` utility path | Implemented target stub. |
| CVE-2025-14931 | smolagents | pickle-backed parsing | Partial placeholder stub; exact API still needs source confirmation. |
| CVE-2025-57622 | Step-Video-T2V | `pickle.loads` endpoint | Source catch only; no stable consumer API identified. |
| CVE-2026-26215 | manga-image-translator | `pickle.loads` endpoint | Validated source-shaped fixture; auth/nonce behavior is out of scope. |
| CVE-2026-25874 | LeRobot | `pickle.loads` over gRPC | Validated source-shaped fixture; channel trust/TLS is out of scope. |
| CVE-2026-23946 | Tendenci | `pickle.loads` report path | Validated source-shaped fixture; authenticated workflow is out of scope. |
| CVE-2025-64512 | pdfminer.six | `pickle.loads` CMap data | Validated source-shaped fixture; consumer PDF API would need a target stub or `TrustedPath`. |
| CVE-2026-3059 | SGLang | `pickle.loads` over ZMQ | Validated source-shaped fixture; broker authentication is out of scope. |
| CVE-2025-56005 | PLY | `pickle.load` via `picklefile` | Validated source-shaped fixture; disputed CVE and public API policy need confirmation. |
| CVE-2025-62703 | Fugue | `cloudpickle.loads` | Sink-family stub implemented; current wrapper remains source-only because upstream moved away from the private helper named in the advisory. |
| CVE-2025-6279 | Upsonic | `cloudpickle.loads` | Sink-family stub implemented; route/API fixture still needed. |
| CVE-2024-10190 | Horovod | `cloudpickle.loads` wrapper | `horovod.runner.common.util.codec.loads_base64` wrapper stub implemented. |
| CVE-2024-9053 | vLLM | `cloudpickle.loads` | Sink-family stub implemented; RPC cloudpickle wrapper remains source-confirmation separate from the implemented PyTorch weight-iterator stubs. |
| CVE-2024-0960 | ai-flow | `cloudpickle.loads` | Sink-family stub implemented; source-shaped fixture still needed. |
| CVE-2020-22083 | jsonpickle | `jsonpickle.decode` | Sink-family stub implemented; disputed/intended-behavior note retained. |
| CVE-2026-22606 | Fickling | analyzer classification | Out of scope. |
| CVE-2026-22607 | Fickling | analyzer classification | Out of scope. |

See [Evidence Appendix](cve-triage.md) for code locations and validation status.

## Current Gaps

- Source-catch-only rows (for example, smolagents, Step-Video-T2V, LeRobot, Tendenci, and SGLang entries) still need stable API-level entry coverage for call-time gates.
- Several OSV-promoted adjacent sink rows remain in partial/non-denominator buckets and are not yet part of the 26-row denominator.
- Out-of-scope categories remain excluded unless they map to a typed deserialization source-to-sink branch.
